import React from 'react';

import {css, StyleSheet} from 'aphrodite';
import PostEditor from '../PostEditor';
import RequireAuth from '../../Auth/RequireAuth/RequireAuth';
import {Redirect} from 'react-router-dom';
import {PostStore} from '../../../data/resource/post';
import {Intent, Position, Toast, Toaster} from '@blueprintjs/core';
import {IconNames} from '@blueprintjs/icons';

const EditorToaster = Toaster.create({
    className: 'recipe-toaster',
    position: Position.TOP
});

class Editor extends React.Component {
    constructor(props) {
        super(props);

        this.state = {
            loading: true,
            toasts: []
        };

        this.toaster = React.createRef();

        this.onSubmit = this.onSubmit.bind(this);
        this.onSubmitDraft = this.onSubmitDraft.bind(this)
    }

    componentDidMount() {

        this.setState({
            post: {
                id: '',
                title: '',
                contents: '',
                tags: []
            },
            loading: false
        })
    }

    onSubmit(postObj) {
        PostStore.createPost(this.state.post.id, {
            ...postObj
        }).then((e) => {
            EditorToaster.show({
                message: 'Updated successfully',
                intent: Intent.SUCCESS,
                icon: IconNames.TICK
            });
            this.setState({
                redirect: `/posts/${e.id}`
            })
        }).catch(err => {
            EditorToaster.show({
                message: 'Failed to update. Error was logged to console.',
                intent: Intent.DANGER,
                icon: IconNames.CROSS
            });
            console.error(err);

        })
    }

    onSubmitDraft() {
    }

    render() {
        if (!this.state.post) {
            return 'Loading...';
        }
        return (
            <div className={css(styles.container)}>
                <RequireAuth from={this.props.match.url}/>
                <Toaster position={Position.TOP_RIGHT} ref={this.toaster}>
                    {this.state.toasts.map(toast => <Toast {...toast} />)}
                </Toaster>
                {this.state.redirect ? <Redirect to={this.state.redirect}/> : ''}
                <PostEditor
                    post={this.state.post} error={this.state.error}
                    loading={this.state.loading}
                    onSubmit={this.onSubmit} type={'create'}
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
