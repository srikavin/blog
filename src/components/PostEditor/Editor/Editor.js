import React from 'react';

import {css, StyleSheet} from 'aphrodite';
import PostEditor from '../PostEditor';
import RequireAuth from '../../Auth/RequireAuth/RequireAuth';
import {Redirect} from 'react-router-dom';
import {PostStore} from '../../../data/resource/post';


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
        console.log(this.props.match.params.id);
        PostStore.getById(this.props.match.params.id)
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
        PostStore.updatePost(this.state.post.id, {
            ...postObj
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
