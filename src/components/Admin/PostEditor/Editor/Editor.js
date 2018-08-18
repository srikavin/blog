import React from 'react';

import {css, StyleSheet} from 'aphrodite';
import PostEditor from '../PostEditor';
import RequireAuth from '../../Auth/RequireAuth/RequireAuth';
import {Redirect} from 'react-router-dom';
import {PostStore} from '../../../../data/resource/post';
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
        PostStore.getById(this.props.match.params.id)
            .then((e) => {
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
        }).then((e) => {
            EditorToaster.show({
                message: 'Updated successfully',
                intent: Intent.SUCCESS,
                icon: IconNames.TICK,
                action: {
                    target: '_blank',
                    href: `/blog/posts/${e.slug}`,
                    text: 'View Post'
                }
            })
        }).catch(err => {
            EditorToaster.show({
                message: 'Failed to update. Error was logged to console.',
                intent: Intent.DANGER,
                icon: IconNames.CROSS
            });
            console.error(err);
        });
    }

    onSubmitDraft(postObj) {
        PostStore.createDraft({
            ...postObj
        }).then((e) => {
            EditorToaster.show({
                message: 'Updated successfully',
                intent: Intent.SUCCESS,
                icon: IconNames.TICK
            })
        }).catch(err => {
            EditorToaster.show({
                message: 'Failed to update. Error was logged to console.',
                intent: Intent.DANGER,
                icon: IconNames.CROSS
            });
            console.error(err);
        });
    }

    render() {
        return (
            <div className={css(styles.container)}>
                <Toaster position={Position.TOP_RIGHT} ref={this.toaster}>
                    {this.state.toasts.map(toast => <Toast {...toast} />)}
                </Toaster>
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
