import React from 'react';

import {store} from '../../../data/store';
import {css, StyleSheet} from 'aphrodite';

import PostEditor from '../PostEditor';
import RequireAuth from '../../Auth/RequireAuth/RequireAuth';
import {Redirect} from 'react-router-dom';


class Editor extends React.Component {
    constructor(props) {
        super(props);

        this.state = {
            loading: true
        };

        this.onSubmit = this.onSubmit.bind(this);
        this.onSubmitDraft = this.onSubmitDraft.bind(this)
    }

    componentDidMount() {
        store.find('post', this.props.match.params.id)
            .then((e) => {
                console.log(e);
                this.setState({
                    post: e
                });
                this.setState({
                    loading: false
                })
            })
            .catch((err) => {
                console.error(err);
                this.setState({
                    error: true,
                    loading: false
                })
            });
    }

    onSubmit(postObj) {
        postObj.tags = [];
        postObj.tagIds = [];
        console.log(postObj);
        store.update('post', this.props.match.params.id, postObj)
            .then(e => {
                this.setState({
                    post: e,
                    redirect: '/post/' + e.slug
                })
            })
            .catch((e) => {
                console.error(e);
                this.setState({
                    error: true
                })
            });
    }

    onSubmitDraft() {
        store.update('post', this.props.match.params.id, {
            ...this.state.post
        }).then(e => {
            this.setState({
                post: e
            })
        }).catch(() => {
            this.setState({
                error: true
            })
        });
    }

    render() {
        console.log(this.state);
        if (!this.state.post) {
            return 'Loading...';
        }
        return (
            <div className={css(styles.container)}>
                <RequireAuth from={this.props.match.url}/>
                {this.state.redirect ? <Redirect to={this.state.redirect}/> : ''}
                <PostEditor
                    post={this.state.post} error={this.state.error}
                    loading={this.state.loading}
                    onSubmit={this.onSubmit} type={'update'}
                    onSubmitDraft={this.onSubmitDraft}
                />
            </div>
        );
    }
}

const styles = StyleSheet.create({
    container: {
        height: '100vh'
    }
});

export default Editor;
